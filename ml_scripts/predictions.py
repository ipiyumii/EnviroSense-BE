import os
from datetime import timedelta
import pandas as pd
from db_util import retrieve_bindata


def update_predictions():
    bin_predictions = []
    data = retrieve_bindata()
    if data is not None and not data.empty:
        os.makedirs('charts', exist_ok=True)
        bin_data_dict = fetch_and_split_data(data)

        unique_bins = data['bin_no'].unique()

        for bin_no, bin_df in bin_data_dict.items():
            predicted_fill_times = predict_fill_times(bin_df)
            time_only = format_times_for_frontend(predicted_fill_times)
            bin_predictions.append({
                'bin_no': bin_no,
                'predictions': time_only
            })
        return bin_predictions
    else:
        return []


def fetch_and_split_data(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.dropna(subset=['timestamp', 'bin_no'], inplace=True)
    df['timestamp'] = df['timestamp'].dt.tz_localize(None)
    df.set_index('timestamp', inplace=True)

    grouped_data = df.groupby('bin_no')
    bin_data_dict = {bin_no: group for bin_no, group in grouped_data}

    return bin_data_dict


def format_times_for_frontend(predicted_times):
    return [time.strftime('%H:%M') for time in predicted_times]

def round_to_nearest_10_minutes(dt):
    minutes = dt.minute
    rounded_minutes = round(minutes / 10) * 10
    if rounded_minutes == 60:
        rounded_minutes = 0
        dt = dt + timedelta(hours=1)
    return dt.replace(minute=rounded_minutes, second=0, microsecond=0)

def predict_fill_times(df,min_count=14):
    df.index = pd.to_datetime(df.index)
    if not isinstance(df.index, pd.DatetimeIndex):
        raise ValueError("Index is not a DatetimeIndex")

    df['rounded_timestamp'] = df.index.to_series().apply(round_to_nearest_10_minutes)
    df['hour'] = df['rounded_timestamp'].dt.hour
    df['minute'] = df['rounded_timestamp'].dt.minute
    df['hour_minute'] = df['hour'].astype(str).str.zfill(2) + ':' + df['minute'].astype(str).str.zfill(2)

    hour_minute_counts = df['hour_minute'].value_counts()
    frequent_hour_minute = hour_minute_counts[hour_minute_counts >= min_count].index.tolist()

    if not frequent_hour_minute:
        return []

    predicted_times = []
    last_date = df.index.normalize().max()

    for hour_min in frequent_hour_minute:
        hour, minute = map(int, hour_min.split(':'))
        next_day_time = last_date + timedelta(days=1) + timedelta(hours=hour, minutes=minute)
        predicted_times.append(next_day_time)
    return predicted_times

def linear_regression_decision(threshold_multiplier=1):
    df = retrieve_bindata()

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
            response = {
                "decisions": f"Change needed for bins: {', '.join(bins_to_change)}" if bins_to_change else "No change needed"
            }
    if bins_to_change:
        return response

