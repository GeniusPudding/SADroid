"""SADroid bytecode instrumentation driver — powered by ApkSmith.

This is the SADroid-specific entry point that:
1. Manages the SQLite DB for app/method hash lookups (SADroid's concern)
2. Delegates the entire decompile/instrument/repack/sign pipeline to ApkSmith

The heavy lifting (smali rewriting, tool discovery, subprocess management)
now lives in the ApkSmith submodule. SADroid only supplies config + a
callback that records method hashes into its own database.
"""

import json
import os
import sys
import sqlite3
from pathlib import Path
from time import process_time

from tqdm import tqdm

# ApkSmith submodule — lives at droidbot/ApkSmith/src/apksmith
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ApkSmith', 'src'))
from apksmith import instrument_apk, InstrumentConfig  # noqa: E402
from apksmith.smali.parser import hash_sign  # noqa: E402


def sadroid_instrument(target_apk_path, target_API_graph, cursor):
    """Instrument a single APK using ApkSmith, recording metadata in SQLite.

    This replaces the old ``methodlog_instrumentation`` — the entire tool
    chain (apktool, zipalign, apksigner) is now managed by ApkSmith.
    """
    apk_path = Path(target_apk_path)
    app_hash = hash_sign(apk_path.stem)
    cursor.execute(
        'INSERT OR IGNORE INTO app (app_hash, app_name) VALUES (?, ?)',
        (app_hash, apk_path.stem),
    )

    def record_method(method_hash, method_sign):
        cursor.execute(
            'INSERT OR IGNORE INTO method (method_hash, method_sign, app_hash) VALUES (?, ?, ?)',
            (method_hash, method_sign, app_hash),
        )

    config = InstrumentConfig(
        keystore=Path(os.path.join(os.getcwd(), 'res', '1.keystore')),
        keystore_pass='s35gj6',
        target_api_graph=target_API_graph,
        log_tag='SADroid',
        on_method=record_method,
    )

    result = instrument_apk(
        apk_path=apk_path,
        output_dir=apk_path.parent,
        config=config,
    )

    print(f'instrumentation done: {result.repacked_apk}')
    print(f'  methods patched: {result.stats.methods_patched}')
    return str(result.repacked_apk)


if __name__ == "__main__":
    conn = sqlite3.connect('data.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS app (app_hash TEXT PRIMARY KEY, app_name TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS method (method_hash TEXT PRIMARY KEY, method_sign TEXT, app_hash TEXT,
                FOREIGN KEY(app_hash) REFERENCES app(app_hash))''')

    with open('jsons/target_API_graph_all.json', 'r') as f:
        target_API_graph = json.load(f)

    data_path = sys.argv[1]

    if data_path.endswith('.apk'):
        repackaged_apk_path = sadroid_instrument(data_path, target_API_graph, c)
        print(f'Instrumentation of {data_path} finished.')
        conn.commit()
        conn.close()
        sys.exit(0)

    dataset = [a for a in os.listdir(data_path) if a.endswith('.apk') and not a.startswith('repacked_')]

    failed_repacked = []
    mean = 0
    for a in tqdm(dataset):
        t1_start = process_time()
        try:
            repackaged_apk_path = sadroid_instrument(os.path.join(data_path, a), target_API_graph, c)
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
