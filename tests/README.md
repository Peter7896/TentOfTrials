# Diagnostic tests

Run the focused diagnostic regression suite from the repository root:

```powershell
python -m unittest discover -s tests -p 'test_build_diagnostics.py' -v
python -m py_compile build.py tests/test_build_diagnostics.py
```

The tests create marked synthetic bytes in temporary directories to check report
and artifact pairing. They do not run `build.py`, invoke encryptly, or verify any
encryption format; passing these tests does not establish encryption validity.
