import os

import pandas as pd
from matplotlib import pyplot as plt
import seaborn as sns
from db_util import retrieve_bindata

def show_bindata():
    data = retrieve_bindata()
    if data is not None and not data.empty:
        print("Columns available before preparation:", data.columns)
        print("Data retrieved:", data.head())

        os.makedirs('charts', exist_ok=True)

        #call methods
        create_line_chart(data)
        create_area_chart(data)
        create_weekly_donut_charts(data)
        create_bar_chart(data)
        create_heat_map(data)

        return "success data process"

def create_line_chart(data):
    df = pd.DataFrame(data, columns=['timestamp', 'bin_no'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    plt.figure(figsize=(12, 6))
    for bin_no in df['bin_no'].unique():
        bin_df = df[df['bin_no'] == bin_no]
        plt.plot(bin_df['timestamp'], [1] * len(bin_df), marker='o', label=f'Bin {bin_no}')

    plt.title('Historical Fill Levels of Bins')
    plt.xlabel('Timestamp')
    plt.ylabel('Fill Event')
    plt.legend()
    plt.savefig('charts/historical_fill_levels.png')
    plt.close()
    print("Line chart created successfully")

def create_area_chart(data):
    df = pd.DataFrame(data, columns=['timestamp', 'bin_no'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    df['fill_event'] = 1

    df.set_index('timestamp', inplace=True)
    df_resampled = df.resample('D').sum()

    plt.figure(figsize=(12, 6))
    plt.fill_between(df_resampled.index, df_resampled['fill_event'], color="skyblue", alpha=0.4)
    plt.plot(df_resampled.index, df_resampled['fill_event'], color="Slateblue", alpha=0.6)
    plt.title('Daily Volume of Waste Collected Over Time')
    plt.xlabel('Date')
    plt.ylabel('Number of Fill Events')
    plt.savefig('charts/area_chart_fill_events.png')
    plt.close()
    print("Area chart created successfully")

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
    print("Donut charts for each bin created successfully")

def create_bar_chart(data):
    df = pd.DataFrame(data, columns=['timestamp', 'bin_no'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    df.set_index('timestamp', inplace=True)

    bin1_df = df[df['bin_no'] == 'A4:CF:12:34:56:78'].resample('W').size()
    bin2_df = df[df['bin_no'] == 'B8:27:EB:98:76:54'].resample('W').size()

    combined_df = pd.DataFrame({
        'Bin A4:CF:12:34:56:78': bin1_df,
        'Bin B8:27:EB:98:76:54': bin2_df
    }).fillna(0)

    combined_df.plot(kind='bar', figsize=(12, 6))
    plt.title('Weekly Fill Frequency for Two Bins')
    plt.xlabel('Week')
    plt.ylabel('Number of Fill Events')
    plt.xticks(rotation=45)
    plt.grid(axis='y')
    plt.legend(title='Bin Number')
    plt.tight_layout()
    plt.savefig('charts/weekly_fill_frequency_columns.png')
    plt.close()
    print("Column chart for bin filling frequency created successfully")

def create_heat_map(data):
    df = pd.DataFrame(data, columns=['timestamp', 'bin_no'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['day_of_week'] = df['timestamp'].dt.day_name()
    df['hour_of_day'] = df['timestamp'].dt.hour

    pivot_table = df.pivot_table(index='day_of_week', columns='hour_of_day', aggfunc='size', fill_value=0)

    days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    pivot_table = pivot_table.reindex(days_order)

    plt.figure(figsize=(12, 6))
    sns.heatmap(pivot_table, cmap='YlGnBu', annot=True, fmt='d')
    plt.title('Time-of-Day and Day-of-Week Patterns for Bin Fullness')
    plt.xlabel('Hour of Day')
    plt.ylabel('Day of Week')
    plt.savefig('charts/bin_fill_patterns_heatmap.png')
    plt.close()
    print("Heatmap created successfully")