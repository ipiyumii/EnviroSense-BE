import os
import pandas as pd
from matplotlib import pyplot as plt
from db_util import retrieve_bindata

def show_bindata():
    data = retrieve_bindata()
    if data is not None and not data.empty:
        print("Columns available before preparation:", data.columns)

        os.makedirs('charts', exist_ok=True)
        create_weekly_donut_charts(data)
        return "success data process"

def create_weekly_donut_charts(data):
    df = pd.DataFrame(data, columns=['timestamp', 'bin_no'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp', inplace=True)
    bins = df['bin_no'].unique()

    for bin_no in bins:
        bin_data = df[df['bin_no'] == bin_no]

        weekly_counts = bin_data.resample('W').size()

        plt.figure(figsize=(8, 8))
        plt.pie(weekly_counts, labels=weekly_counts.index.strftime('%Y-%m-%d'), autopct='%1.1f%%', startangle=140,
                wedgeprops=dict(width=0.4))
        plt.title(f'Bin {bin_no} Weekly Fill Frequency Donut Chart')
        plt.savefig(f'charts/bin_{bin_no}_weekly_donut_chart.png')
        plt.close()






