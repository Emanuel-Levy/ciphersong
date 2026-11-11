import os

BASE_PUBSPEC = """name: 'ciphersong'
description: "Detector Vocal de Tom em Tempo Real (RAM-Only) e Repertório de Músicas Ensaiadas"
publish_to: none
version: 1.0.0+1
environment:
  sdk: '>=3.1.5 <4.0.0'
dependencies:
  flutter:
    sdk: flutter
  flutter_web_plugins:
    sdk: flutter
  cupertino_icons: ^1.0.8
  flet: 1.0.4
  serious_python: 5.0.0
  msgpack_dart: ^1.0.1
  package_info_plus: ^9.0.0
  path_provider: ^2.1.4
  path: ^1.9.0
  window_manager: ^0.5.1
dependency_overrides:
  flet: 1.0.4
dev_dependencies:
  flutter_lints: ^2.0.0
flutter:
  uses-material-design: true
"""

# 1. Manage build/flutter/pubspec.yaml
import importlib.util
import shutil

pubspec_path = os.path.join("build", "flutter", "pubspec.yaml")
flutter_pkg_path = os.path.join("build", "flutter-packages", "flet_audio_recorder")

if not os.path.exists(flutter_pkg_path):
    spec = importlib.util.find_spec("flet_audio_recorder")
    if spec and spec.origin:
        site_flutter = os.path.join(os.path.dirname(os.path.dirname(spec.origin)), "flutter", "flet_audio_recorder")
        if os.path.exists(site_flutter):
            os.makedirs(os.path.dirname(flutter_pkg_path), exist_ok=True)
            shutil.copytree(site_flutter, flutter_pkg_path)
            print("[OK] flet_audio_recorder sincronizado para build/flutter-packages.")

if os.path.exists(pubspec_path):
    with open(pubspec_path, "r", encoding="utf-8") as f:
        content = f.read()
    if os.path.exists(flutter_pkg_path):
        if "flet_audio_recorder:" not in content:
            abs_pkg = os.path.abspath(flutter_pkg_path)
            content = content.replace(
                "flet: 1.0.4\n",
                f"flet: 1.0.4\n  flet_audio_recorder:\n    path: {abs_pkg}\n"
            )
            with open(pubspec_path, "w", encoding="utf-8") as f:
                f.write(content)
            print("[OK] build/flutter/pubspec.yaml sincronizado com flet_audio_recorder.")
    else:
        if "flet_audio_recorder:" in content:
            with open(pubspec_path, "w", encoding="utf-8") as f:
                f.write(BASE_PUBSPEC)
            print("[OK] build/flutter/pubspec.yaml restaurado sem referencia quebrada.")

# 2. Verify build/flutter/lib/python.dart has valid AST
dart_path = os.path.join("build", "flutter", "lib", "python.dart")
if os.path.exists(dart_path):
    with open(dart_path, "r", encoding="utf-8") as f:
        code = f.read()
    import re, ast
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
            print("[OK] build/flutter/lib/python.dart validado com sucesso (zero erros de sintaxe).")
        except Exception as e:
            print("[ERRO CRITICO EM python.dart]:", e)
            raise
