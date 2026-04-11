import os
import shutil
import json
import sys
import subprocess
from time import process_time
import sqlite3

from tqdm import tqdm
from smali_utils.core_SADroid_logger import walk_smali_dir, hash_sign


# --- external tool resolution ----------------------------------------------
# apktool is a shell/batch wrapper; on Windows it is typically `apktool.bat`,
# elsewhere plain `apktool`. Accept either so the pipeline works cross-platform
# without requiring callers to know which one their PATH exposes.

def _find_tool(names):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def resolve_apktool(override=None):
    if override:
        return override
    found = _find_tool(["apktool", "apktool.bat"])
    if not found:
        raise RuntimeError("Could not find 'apktool' or 'apktool.bat' on PATH.")
    return found


def resolve_zipalign(override=None):
    if override:
        return override
    found = _find_tool(["zipalign"])
    if not found:
        raise RuntimeError("Could not find 'zipalign' on PATH (ships with Android SDK build-tools).")
    return found


def resolve_apksigner(override=None):
    if override:
        return override
    found = _find_tool(["apksigner", "apksigner.bat"])
    if not found:
        raise RuntimeError("Could not find 'apksigner' on PATH (ships with Android SDK build-tools).")
    return found


def _run(cmd, label):
    """Run a subprocess list-argv, capturing stdout/stderr for diagnostics."""
    print(f"[{label}] $ {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError as e:
        raise RuntimeError(f"{label} failed: executable not found ({e.filename})") from e
    except subprocess.CalledProcessError as e:
        tail_out = (e.stdout or "").strip()[-2000:]
        tail_err = (e.stderr or "").strip()[-2000:]
        raise RuntimeError(
            f"{label} failed with exit code {e.returncode}\n--- stdout ---\n{tail_out}\n--- stderr ---\n{tail_err}"
        ) from e
    if proc.stdout:
        print(proc.stdout.rstrip())
    return proc


def patch_log_file(smali_base_dir):
    inject_dir = os.path.join(smali_base_dir, 'SADroid')
    if not os.path.isdir(inject_dir):
        os.mkdir(inject_dir)
    shutil.copyfile(
        os.path.join(os.path.dirname(__file__), 'smali_utils', 'injections', 'logs', 'InlineLogs.smali'),
        os.path.join(inject_dir, 'InlineLogs.smali'),
    )


def methodlog_instrumentation(
    target_apk_path,
    redecompile,
    target_API_graph,
    cursor,
    *,
    keystore_path=None,
    keystore_pass=None,
    key_alias=None,
    key_pass=None,
    apktool_path=None,
    zipalign_path=None,
    apksigner_path=None,
    extra_on_method=None,
):
    """Decompile a single APK, instrument every main-class method, repack and sign.

    Tool paths default to whatever is on PATH (apktool, zipalign, apksigner).
    Signing credentials default to the research keystore under ``res/1.keystore``
    with password ``s35gj6`` to preserve current SADroid behaviour, but any of
    those can be overridden by the caller.
    """
    print(f'testing_apk_path:{target_apk_path}')
    if not os.path.exists(target_apk_path):
        raise ValueError("APK does not exist.")

    apktool = resolve_apktool(apktool_path)
    zipalign = resolve_zipalign(zipalign_path)
    apksigner = resolve_apksigner(apksigner_path)

    ks_path = keystore_path if keystore_path is not None else os.path.join(os.getcwd(), 'res', '1.keystore')
    ks_pass = keystore_pass if keystore_pass is not None else 's35gj6'
    k_pass = key_pass if key_pass is not None else ks_pass

    dirname, basename = os.path.split(target_apk_path)
    app_name = os.path.splitext(basename)[0]
    app_hash = hash_sign(app_name)
    cursor.execute('INSERT OR IGNORE INTO app (app_hash, app_name) VALUES (?, ?)', (app_hash, app_name))

    # SADroid persists method_hash -> method_sign into its own SQLite DB.
    # The rewriting engine in smali_utils does not know or care about that:
    # it just fires this callback once per patched method. Keeping the
    # persistence concern here (rather than inside the engine) is what
    # lets ApkSmith reuse the engine without pulling in SQLite.
    def record_method(method_hash, method_sign):
        cursor.execute(
            'INSERT OR IGNORE INTO method (method_hash, method_sign, app_hash) VALUES (?, ?, ?)',
            (method_hash, method_sign, app_hash),
        )
        if extra_on_method is not None:
            extra_on_method(method_hash, method_sign)

    apktool_dir = os.path.join(dirname, app_name)

    # 1. apktool decompile
    if redecompile:
        _run(
            [apktool, '-rf', 'd', '--only-main-classes', target_apk_path, '-o', apktool_dir],
            label='apktool d',
        )

    # 2. bytecode instrumentation
    print('bytecode instrumentation')
    smali_dirs = [subdir for subdir in os.listdir(apktool_dir) if subdir.startswith('smali')]
    for subdir in smali_dirs:
        smali_base_dir = os.path.join(apktool_dir, subdir)
        walk_smali_dir(smali_base_dir, target_API_graph, app_hash, on_method=record_method)
    patch_log_file(os.path.join(apktool_dir, 'smali'))

    # 3. apk repackage -> zipalign -> sign
    print('test repackage')
    try:
        _run([apktool, 'b', apktool_dir], label='apktool b')

        build_path = os.path.join(apktool_dir, 'dist', app_name + '.apk')
        build_path2 = os.path.join(apktool_dir, 'dist', app_name + '_2.apk')
        repackaged_apk_path = os.path.join(dirname, 'repacked_' + app_name + '.apk')

        _run([zipalign, '-f', '-v', '4', build_path, build_path2], label='zipalign')

        sign_cmd = [
            apksigner, 'sign',
            '--ks', ks_path,
            '--ks-pass', 'pass:' + ks_pass,
            '--key-pass', 'pass:' + k_pass,
            '--out', repackaged_apk_path,
        ]
        if key_alias:
            sign_cmd += ['--ks-key-alias', key_alias]
        sign_cmd.append(build_path2)
        _run(sign_cmd, label='apksigner')
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f'Failed to repackage: {e}') from e

    print(f'methodlog_instrumentation:{repackaged_apk_path}')
    return repackaged_apk_path


if __name__ == "__main__":
    conn = sqlite3.connect('data.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS app (app_hash TEXT PRIMARY KEY, app_name TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS method (method_hash TEXT PRIMARY KEY, method_sign TEXT, app_hash TEXT,
                FOREIGN KEY(app_hash) REFERENCES app(app_hash))''')

    with open('jsons/target_API_graph_all.json', 'r') as f:
        target_API_graph = json.load(f)
    data_path = sys.argv[1]
    if data_path[-4:] == '.apk':
        repackaged_apk_path = methodlog_instrumentation(data_path, True, target_API_graph, c)
        print(f'Instrumentation of {data_path} finished.')
        conn.commit()
        conn.close()
        sys.exit(0)

    dd = os.listdir(data_path)
    dataset = [a for a in dd if a[-4:] == '.apk' and not a.startswith('repacked_')]

    failed_repacked = []
    mean = 0
    for a in tqdm(dataset):
        t1_start = process_time()
        try:
            repackaged_apk_path = methodlog_instrumentation(os.path.join(data_path, a), True, target_API_graph, c)
        except Exception as e:
            print(f'Analyzing {a} failed, error:{e}')
            failed_repacked.append(a)
        t1_stop = process_time()
        t = t1_stop - t1_start
        print(f'Time for {a}: {t}')
        mean += t
    if dataset:
        mean /= len(dataset)
    conn.commit()
    conn.close()
    print(f'平均執行時間:{mean}')
    print(f'failed_repacked:{failed_repacked}')
