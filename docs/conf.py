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


def setup(app):
    app.connect("autoapi-skip-member", autoapi_skip_member)
