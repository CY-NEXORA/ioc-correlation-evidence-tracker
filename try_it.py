import pandas as pd
from src.normalizer import normalize_ioc_dataframe

df = pd.read_csv("data/iocs.csv")
valid, rejected = normalize_ioc_dataframe(df)

print("=== المؤشرات السليمة ===")
print(valid[["norm_value", "norm_type", "source"]].to_string())

print("\n=== المؤشرات المرفوضة ===")
print(rejected[["row_id", "value", "reason"]].to_string())
