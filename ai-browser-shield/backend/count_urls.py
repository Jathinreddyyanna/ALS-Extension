import pandas as pd
df = pd.read_csv('data/malicious_phish.csv')
print(f'Total URLs: {len(df)}')
print(f'\nDistribution:')
print(df['type'].value_counts())
