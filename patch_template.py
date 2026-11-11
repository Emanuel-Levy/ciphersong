import zipfile, os, shutil, re, ast

zpath = r"C:\Users\Levy\.flet\cache\build-template\v1.0.4\flet-build-template.zip"
bakpath = zpath + ".bak"
if not os.path.exists(bakpath):
    shutil.copyfile(zpath, bakpath)

# Always restore clean original from .bak first to guarantee pristine state
shutil.copyfile(bakpath, zpath)

target_entry = "build/{{cookiecutter.out_dir}}/lib/python.dart"
entries = {}
with zipfile.ZipFile(zpath, "r") as z:
    for item in z.infolist():
        entries[item.filename] = z.read(item.filename)

code = entries[target_entry].decode("utf-8")

target_block = '''    import certifi

    os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
    os.environ["SSL_CERT_FILE"] = certifi.where()'''

replacement_block = '''    try:
        import certifi
        _ca = certifi.where()
        os.environ["REQUESTS_CA_BUNDLE"] = _ca
        os.environ["SSL_CERT_FILE"] = _ca
    except Exception:
        _ca = None'''

if target_block in code:
    code = code.replace(target_block, replacement_block)
    code = code.replace("cafile=certifi.where()", "cafile=_ca or cafile")
    entries[target_entry] = code.encode("utf-8")
    with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for fname, data in entries.items():
            z.writestr(fname, data)
    print("SUCCESS: Template python.dart patched cleanly and safely!")
else:
    print("Target certifi block not found or already patched.")

# AST verification
match = re.search(r'const pythonScript =\s*"""(.*?)""";', code, re.DOTALL)
if match:
    py_code = match.group(1)
    py_code = py_code.replace('{outLogFilename}', '"out.log"')
    py_code = py_code.replace('{argv}', '[]')
    py_code = py_code.replace('{host_executable}', 'None')
    py_code = py_code.replace('{module_name}', '"main"')
    py_code = py_code.replace('$errorExitCode', '100')
    try:
        ast.parse(py_code)
        print("AST VALIDATION: PASSED 100%! Python script has zero syntax errors.")
    except Exception as e:
        print("AST VALIDATION FAILED:", e)
        raise
