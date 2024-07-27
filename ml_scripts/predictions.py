import os
from datetime import timedelta, datetime
import matplotlib.dates as mdates
import pandas as pd
from matplotlib import pyplot as plt, patches
import plotly.express as px
from db_util import retrieve_bindata

def update_predictions():
    data = retrieve_bindata()
    if data is not None and not data.empty:
        print("Columns available before preparation:", data.columns)
        print("Data retrieved:", data.head())


        original_data = data.copy()

        os.makedirs('charts', exist_ok=True)

        bin1_df, bin2_df = fetch_and_split_data(data)
        predicted_bin1_fill_times = predict_fill_times(bin1_df)
        predicted_bin2_fill_times = predict_fill_times(bin2_df)

        time_only_bin1 = format_times_for_frontend(predicted_bin1_fill_times)
        time_only_bin2 = format_times_for_frontend(predicted_bin2_fill_times)

        create_gantt_chart(predicted_bin1_fill_times, predicted_bin2_fill_times)
        create_calendar_heatmap(predicted_bin1_fill_times, predicted_bin2_fill_times)
        create_interactive_timeline_chart(predicted_bin1_fill_times, predicted_bin2_fill_times)

        # decisions = linear_regression_decision(original_data)

        return {
            'bin1_next_day_prediction': time_only_bin1,
            'bin2_next_day_prediction': time_only_bin2,
            # 'decisions': decisions
        }
    else:
        return {
            'bin1_next_day_prediction': None,
            'bin2_next_day_prediction': None,
            # 'decisions': "No data available"
        }

def fetch_and_split_data(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp', 'bin_no'], inplace=True)
    df['timestamp'] = df['timestamp'].dt.tz_localize(None)
    df.set_index('timestamp', inplace=True)

    bin1_df = df[df['bin_no'] == "A4:CF:12:34:56:78"]
    bin2_df = df[df['bin_no'] == "B8:27:EB:98:76:54"]

    print("Bin 1 DataFrame columns:", bin1_df.columns)
    print("Bin 2 DataFrame columns:", bin2_df.columns)

    return bin1_df, bin2_df

def format_times_for_frontend(predicted_times):
    # Convert list of datetime objects to time-only strings
    return [time.strftime('%H:%M') for time in predicted_times]

def round_to_nearest_10_minutes(dt):
    minutes = dt.minute
    rounded_minutes = round(minutes / 10) * 10
    if rounded_minutes == 60:
        rounded_minutes = 0
        dt = dt + timedelta(hours=1)
    return dt.replace(minute=rounded_minutes, second=0, microsecond=0)

def predict_fill_times(df,min_count=10):
    df = df.copy()

    df['rounded_timestamp'] = df.index.to_series().apply(round_to_nearest_10_minutes)

    df['hour'] = df['rounded_timestamp'].dt.hour
    df['minute'] = df['rounded_timestamp'].dt.minute
    df['hour_minute'] = df['hour'].astype(str).str.zfill(2) + ':' + df['minute'].astype(str).str.zfill(2)
    hour_minute_counts = df['hour_minute'].value_counts()
    print(f"Hour-Minute counts for bin {df['bin_no'].iloc[0]}: {hour_minute_counts}")

    frequent_hour_minute = hour_minute_counts[hour_minute_counts >= min_count].index.tolist()
    print(f"Frequent hour-minute combinations for bin {df['bin_no'].iloc[0]}: {frequent_hour_minute}")

    if not frequent_hour_minute:
        print(f"No hour-minute combinations meet the minimum count requirement for bin {df['bin_no'].iloc[0]}.")
        return []

    predicted_times = []
    last_date = df.index.normalize().max()

    for hour_min in frequent_hour_minute:
        hour, minute = map(int, hour_min.split(':'))
        next_day_time = last_date + timedelta(days=1) + timedelta(hours=hour, minutes=minute)
        # predicted_times.append(next_day_time.strftime('%Y-%m-%d %H:%M:%S'))
        predicted_times.append(next_day_time)
    print(
        f"Predicted fill times for the next day for bin {df['bin_no'].iloc[0]}: {predicted_times}")
    return predicted_times

def calculate_pred(df):
    if 'timestamp' not in df.columns:
        raise KeyError("The 'timestamp' column is missing from the DataFrame")

    df['timestamp'] = pd.to_datetime(df['timestamp'])

    def predict_timestamps(bin_data):
        bin_data = bin_data.sort_values('timestamp')
        bin_data['Time_Diff'] = bin_data['timestamp'].diff().dt.total_seconds().dropna()
        moving_avg = bin_data['Time_Diff'].rolling(window=3).mean().dropna()
        last_timestamp = bin_data['timestamp'].iloc[-1]
        predictions = []
        for i in range(3):
            next_timestamp = last_timestamp + timedelta(seconds=moving_avg.iloc[-1])
            predictions.append(next_timestamp)
            last_timestamp = next_timestamp
        return predictions

    predictions = df.groupby('bin_no').apply(predict_timestamps).reset_index()
    predictions.columns = ['bin_no', 'Predicted Timestamps']
    print(predictions)

    return predictions

def linear_regression_decision(df,threshold_multiplier=2):
    df['date'] = df['timestamp'].dt.date
    emptying_counts_per_day = df.groupby(['bin_no', 'date']).size().reset_index(name='emptying_count')

    bins_to_change = []
    for bin_no, group in emptying_counts_per_day.groupby('bin_no'):
        if len(group) <= 3:
            continue

        mean_count = group['emptying_count'].mean()
        std_count = group['emptying_count'].std()

        recent_counts = group.iloc[-3:]['emptying_count']
        change_needed = recent_counts.apply(lambda count: count > mean_count + threshold_multiplier * std_count).any()

        if change_needed:
            bins_to_change.append(bin_no)

    if bins_to_change:
        return f"Change needed for bins: {', '.join(bins_to_change)}"
    else:
        return "No change needed"

def create_gantt_chart(predicted_bin1_fill_times, predicted_bin2_fill_times):
    def to_datetime(times):
        if isinstance(times[0], str):
            return [datetime.strptime(time, '%Y-%m-%d %H:%M:%S') for time in times]
        return times

    predicted_bin1_fill_times = to_datetime(predicted_bin1_fill_times)
    predicted_bin2_fill_times = to_datetime(predicted_bin2_fill_times)

    df = pd.DataFrame({
        'Task': ['Bin 1'] * len(predicted_bin1_fill_times) + ['Bin 2'] * len(predicted_bin2_fill_times),
        'Start': predicted_bin1_fill_times + predicted_bin2_fill_times,
        'End': [time + timedelta(minutes=15) for time in predicted_bin1_fill_times] +
               [time + timedelta(minutes=15) for time in predicted_bin2_fill_times]
    })

    df['Start'] = pd.to_datetime(df['Start'])
    df['End'] = pd.to_datetime(df['End'])

    fig, ax = plt.subplots(figsize=(12, 6))

    for i, task in enumerate(df['Task'].unique()):
        task_df = df[df['Task'] == task]
        ax.broken_barh(
            [(start, end - start) for start, end in zip(task_df['Start'], task_df['End'])],
            (i - 0.4, 0.8),
            facecolors=('tab:blue' if task == 'Bin 1' else 'tab:orange')
        )
    ax.set_yticks(range(len(df['Task'].unique())))
    ax.set_yticklabels(df['Task'].unique())
    ax.set_xlabel('Time')
    ax.set_title('Predicted Fill Times for Bins')
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
    plt.xticks(rotation=45)
    plt.savefig('charts/gantt_chart.png')
    plt.close()

    print("Gantt chart created successfully")

def create_calendar_heatmap(predicted_bin1_fill_times, predicted_bin2_fill_times):
    all_fill_times = predicted_bin1_fill_times + predicted_bin2_fill_times
    if not all_fill_times:
        print("No fill times available for heatmap.")
        return
    df = pd.DataFrame({'Timestamp': all_fill_times})
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')  # Convert to datetime and handle errors

    if df['Timestamp'].isnull().all():
        print("No valid datetime entries found.")
        return

    df['Date'] = df['Timestamp'].dt.date
    df['Hour'] = df['Timestamp'].dt.hour

    fill_counts = df.groupby(['Date', 'Hour']).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(14, 10))

    for i, (date, counts) in enumerate(fill_counts.iterrows()):
        for hour, count in counts.items():
            if count > 0:
                ax.add_patch(patches.Rectangle(
                    (hour, i), 1, 1,
                    color='blue', alpha=min(count/len(all_fill_times), 1.0)
                ))

    ax.set_xlabel('Hour of Day')
    ax.set_ylabel('Date')
    ax.set_title('Calendar Heatmap of Predicted Fill Times')
    ax.set_xticks(range(24))
    ax.set_xticklabels([f'{hour}:00' for hour in range(24)])
    ax.set_yticks(range(len(fill_counts)))
    ax.set_yticklabels([date.strftime('%Y-%m-%d') for date in fill_counts.index])
    plt.xticks(rotation=45)
    plt.savefig('charts/calendar_heatmap.png')
    plt.close()

def create_interactive_timeline_chart(predicted_bin1_fill_times, predicted_bin2_fill_times):
    events = pd.DataFrame({
        'Timestamp': predicted_bin1_fill_times + predicted_bin2_fill_times,
        'Bin': ['Bin 1'] * len(predicted_bin1_fill_times) + ['Bin 2'] * len(predicted_bin2_fill_times)
    })

    fig = px.scatter(events, x='Timestamp', y=[0] * len(events), color='Bin',
                     labels={'Timestamp': 'Time', 'y': ''},
                     title='Predicted Fill Times Timeline')

    fig.update_layout(yaxis_visible=False, yaxis_showgrid=False)
    fig.update_traces(marker=dict(size=10, line=dict(width=2, color='DarkSlateGrey')),
                      selector=dict(mode='markers+text'))

    fig.write_html('charts/interactive_timeline_chart.html')

    print("Interactive timeline chart created successfully")

