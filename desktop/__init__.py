"""Desktop launcher package.

Deliberately NOT named ``packaging``: that name belongs to the pip/setuptools
dependency, and a local directory with that name shadows it (a regular package
in site-packages wins over a local namespace package, which is how the clash
was first caught). Shadowing ``packaging`` would break pip inside this folder.
"""
