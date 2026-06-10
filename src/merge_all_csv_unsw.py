import pandas as pd
import config

# ======================================================
# LOAD CSV FILES
# ======================================================

columns = [
    "srcip",
    "sport",
    "dstip",
    "dsport",
    "proto",
    "state",
    "dur",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "sloss",
    "dloss",
    "service",
    "sload",
    "dload",
    "spkts",
    "dpkts",
    "swin",
    "dwin",
    "stcpb",
    "dtcpb",
    "smeansz",
    "dmeansz",
    "trans_depth",
    "res_bdy_len",
    "sjit",
    "djit",
    "stime",
    "ltime",
    "sintpkt",
    "dintpkt",
    "tcprtt",
    "synack",
    "ackdat",
    "is_sm_ips_ports",
    "ct_state_ttl",
    "ct_flw_http_mthd",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_srv_src",
    "ct_srv_dst",
    "ct_dst_ltm",
    "ct_src_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "attack_cat",
    "label"
]

print("Loading CSV files...")

df1 = pd.read_csv(config.UNSW.get("csv_files_1"),sep=",",low_memory=False,header=None, names=columns)
print(f"df1 shape={df1.shape} column_count={df1.columns.to_list()}")
df2 = pd.read_csv(config.UNSW.get("csv_files_2"),sep=",",low_memory=False,header=None, names=columns)
print(f"df2 shape={df2.shape} column_count={df2.columns.tolist()}")
df3 = pd.read_csv(config.UNSW.get("csv_files_3"),sep=",",low_memory=False,header=None, names=columns)
print(f"df2 shape={df2.shape} column_count={df2.columns.tolist()}")
df4 = pd.read_csv(config.UNSW.get("csv_files_4"),sep=",",low_memory=False,header=None, names=columns)
print(f"df2 shape={df2.shape} column_count={df2.columns.tolist()}")

# ======================================================
# MERGE DATASETS
# ======================================================

print("Merging datasets...")

df = pd.concat(
    [df1, df2, df3, df4],
    ignore_index=True
)

# ======================================================
# REMOVE DUPLICATES
# ======================================================

print("Removing duplicates...")

before = len(df)

df = df.drop_duplicates()

after = len(df)

print(f"Removed {before - after} duplicate rows")

# ======================================================
# SHOW DATASET INFO
# ======================================================

print("\nFinal Dataset Shape:")

print(df.shape)


# ======================================================
# SAVE MERGED DATASET
# ======================================================

output_file = config.UNSW.get("merged_ml_csv")

print(f"\nSaving merged dataset to: {output_file}")

df.to_csv(
    output_file,
    index=False
)

print("\nSaved successfully!")