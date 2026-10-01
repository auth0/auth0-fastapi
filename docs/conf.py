import json
import os
import sys

sys.path.insert(0, os.path.abspath("../src"))

# -- Project info -------------------------------------------------------

project = "auth0-fastapi"
author = "Auth0"
copyright = "2024, Auth0"
release = "1.0.0b11"

# -- Extensions ---------------------------------------------------------

extensions = [
    "autoapi.extension",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
]

# -- AutoAPI ------------------------------------------------------------

autoapi_dirs = ["../src"]
autoapi_type = "python"
autoapi_root = "reference"
autoapi_ignore = ["**/test/**", "**/test_*.py"]


def autoapi_skip_member(app, what, name, obj, skip, options):
    # Suppress Pydantic's inner Config class (exposes "self is positional-only" noise)
    if what == "class" and name.endswith(".Config"):
        return True
    return skip


autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
]
autoapi_member_order = "groupwise"
autoapi_keep_files = True
autoapi_template_dir = "_templates/autoapi"
autoapi_python_class_content = "class"  # exclude auto-generated __init__ docstrings

# -- Napoleon (docstring style) -----------------------------------------

napoleon_google_docstring = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = True

# -- Intersphinx --------------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

# -- HTML output --------------------------------------------------------

html_theme = "furo"
html_title = "auth0-fastapi"
html_static_path = ["_static"]
html_css_files = ["auth0.css"]
html_theme_options = {
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
    "light_css_variables": {
        "color-brand-primary": "#9921FE",
        "color-brand-content": "#9921FE",
    },
    "dark_css_variables": {
        "color-brand-primary": "#BC6DFF",
        "color-brand-content": "#BC6DFF",
    },
}

# -- General ------------------------------------------------------------

exclude_patterns = ["_build", "_templates", "Thumbs.db", ".DS_Store", "superpowers"]

# -- Mintlify / docs-v2 post-processing ---------------------------------
# Path prefix used by docs-v2 when the artifact is placed under sdk-artifacts/auth0-fastapi
DOCS_V2_DIRECTORY = "docs/sdk/python/fastapi"

# Title overrides: map page path (relative to _build/json/) to display title
TITLE_OVERRIDES = {
    "reference/auth0_fastapi/config/index": "Auth0Config",
    "reference/auth0_fastapi/errors/index": "ConfigurationError",
}

# Module-level index pages with no content beyond a child list - redundant in Mintlify
REMOVE_PAGES = [
    "reference/auth0_fastapi/index",
    "reference/auth0_fastapi/auth/index",
    "reference/auth0_fastapi/server/index",
    "reference/auth0_fastapi/stores/index",
]

# Sidebar navigation emitted to navigation.json for docs-v2.
# Update this list when modules are added or removed from the SDK.
DOCS_V2_NAVIGATION = [
    {
        "group": "Overview",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/index"],
    },
    {
        "group": "Auth",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/auth/auth_client/index"],
    },
    {
        "group": "Config",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/config/index"],
    },
    {
        "group": "Server",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/server/routes/index"],
    },
    {
        "group": "Stores",
        "pages": [
            f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/stores/cookie_transaction_store/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/stores/stateful_state_store/index",
            f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/stores/stateless_state_store/index",
        ],
    },
    {
        "group": "Errors",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/errors/index"],
    },
    {
        "group": "Utilities",
        "pages": [f"{DOCS_V2_DIRECTORY}/reference/auth0_fastapi/util/index"],
    },
]


def _postprocess_json_build(app, exception):
    """Run after `sphinx -b json`. Cleans up boilerplate and writes navigation.json."""
    if exception or app.builder.name != "json":
        return

    out = app.outdir

    # Apply title overrides
    for page_path, title in TITLE_OVERRIDES.items():
        fpath = os.path.join(out, page_path + ".fjson")
        if not os.path.exists(fpath):
            continue
        with open(fpath) as f:
            data = json.load(f)
        data["title"] = title
        with open(fpath, "w") as f:
            json.dump(data, f, indent=2)

    # Remove orphan module-level index pages
    for page_path in REMOVE_PAGES:
        fpath = os.path.join(out, page_path + ".fjson")
        if os.path.exists(fpath):
            os.remove(fpath)

    # Clean reference/index.fjson: strip sphinx-autoapi boilerplate
    index_path = os.path.join(out, "reference", "index.fjson")
    if os.path.exists(index_path):
        with open(index_path) as f:
            data = json.load(f)
        data["body"] = ""
        with open(index_path, "w") as f:
            json.dump(data, f, indent=2)

    # Write navigation.json so docs-v2 does not need to maintain it separately
    nav_path = os.path.join(out, "navigation.json")
    with open(nav_path, "w") as f:
        json.dump({"pages": DOCS_V2_NAVIGATION}, f, indent=2)

    print(f"[auth0-fastapi] Wrote {nav_path}")


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
    app.connect("build-finished", _postprocess_json_build)
