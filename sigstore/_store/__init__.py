# NOTE: This is arguably incorrect, since _store only contains non-Python files.
# However, due to how `importlib.resources` is designed, only top-level resources
# inside of packages or modules can be accessed, so this directory needs to be a
# module in order for us to programmatically access the keys and root certs in it.
#
# Why do we bother with `importlib` at all? Because we might be installed as a
# ZIP file or an Egg, which in turn means that our resource files don't actually
# exist separately on disk. `importlib` is the only reliable way to access them.
