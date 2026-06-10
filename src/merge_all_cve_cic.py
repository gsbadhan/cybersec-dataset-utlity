import pandas as pd
import glob

# Load all CSV files
files = glob.glob(
    "/Users/gurpreetsingh/Downloads/cybersec-dataset/cic/2017/ids/MachineLearningCVE/*.csv"
)

# Merge all CSVs
df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)


# Clean column names
df.columns = (
    df.columns
      .str.strip()                             # remove leading/trailing spaces
      .str.replace('.1', '', regex=False)     # remove .1
      .str.replace(' ', '_', regex=False)     # replace spaces with _
      .str.replace('/', '_per_', regex=False) # replace / with _per_
      .str.replace('-', '_', regex=False)     # replace - with _
      .str.lower()                            # lowercase
)

# Remove duplicate columns
df = df.loc[:, ~df.columns.duplicated()]


# Show cleaned columns
print(f"✓ Loaded {len(df):,} rows with {len(df.columns)} columns")
print(df.columns.tolist())

# Save merged cleaned dataset
output_path = (
    "/Users/gurpreetsingh/Downloads/cybersec-dataset/cic/2017/ids/cic_machine_learning_cve_merged.csv"
)

df.to_csv(output_path, index=False)

print(f"✓ Saved merged dataset to:\n{output_path}")