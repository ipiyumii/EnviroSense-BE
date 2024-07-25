import base64
from datetime import datetime, timedelta
from io import BytesIO

from sklearn.linear_model import LinearRegression

from db_util import retrieve_bindata
import mysql.connector
import pandas as pd
import matplotlib.pyplot as plt
from prophet import Prophet
predicted_timestamps = {}
import json
import os


def update_predictions():
    data = retrieve_bindata()
    if data is not None and not data.empty:
        print("Columns available before preparation:", data.columns)
        print("Data retrieved:", data.head())

        original_data = data.copy()
        predictions = calculate_pred(data)

        # predictions = predict_future_timestamps(prepared_data)
        print("Predictions:", predictions)
        predictions_dict = predictions.to_dict(orient='records')
        # Get decisions (assuming this is implemented elsewhere)
        decisions = linear_regression_decision(original_data)

        return {
            'predictions': predictions_dict,
            'decisions': decisions
        }
    else:
        return {
            'predictions': {},
            'decisions': "No data available"
        }


def calculate_pred(df):
    if 'timestamp' not in df.columns:
        raise KeyError("The 'timestamp' column is missing from the DataFrame")

    # Convert 'timestamp' to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Predict timestamps for today using moving average
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

def get_historical_filling_times(df):
    # Extract time of day from the index
    df['hour'] = df.index.hour
    df['minute'] = df.index.minute
    times = df.groupby(['hour', 'minute']).size().reset_index(name='count')
    times = times.sort_values(by='count', ascending=False)
    return times[['hour', 'minute']].values.tolist()



def predict_future_timestamps(df, num_predictions=3):
    predictions = {}

    for bin_name, group in df.groupby('bin_no'):
        # Determine historical filling times
        historical_times = get_historical_filling_times(group)

        # Predict future timestamps
        last_date = group.index[-1]
        bin_predictions = []

        for i in range(1, num_predictions + 1):
            future_date = last_date + pd.DateOffset(days=i)
            for hour, minute in historical_times:
                future_time = pd.Timestamp(f"{future_date.date()} {hour:02d}:{minute:02d}:00")
                bin_predictions.append(f"Predicted at {hour:02d}:{minute:02d}")

        predictions[bin_name] = bin_predictions

    return predictions



def predict_next_filling_times(df):
    # Convert timestamp to date for daily aggregation
    df['date'] = df['timestamp'].dt.date
    grouped = df.groupby(['bin_no', 'date']).size().reset_index(name='fill_count')

    print("Grouped data:\n", grouped)

    def predict_next_fill(group, window=7):
        """Calculate moving average and predict the next fill timestamp based on the average interval."""
        group['moving_avg'] = group['fill_count'].rolling(window=window, min_periods=1).mean()

        print(f"Data for bin {group['bin_no'].iloc[0]}:\n", group)

        average_fill = group['moving_avg'].iloc[-1]
        print("Average fill count:", average_fill)

        if average_fill > 0:
            # Average interval between fills in days
            average_interval = timedelta(days=window) / average_fill
            last_fill_date = pd.to_datetime(group['date'].max())
            next_fill_date = last_fill_date + average_interval
            print(f"Last fill date for bin {group['bin_no'].iloc[0]}:", last_fill_date)
            print(f"Predicted next fill date for bin {group['bin_no'].iloc[0]}:", next_fill_date)
            return next_fill_date.strftime('%Y-%m-%d %H:%M:%S')
        else:
            return "No fills in window"

    predictions = {}
    for bin_no, group in grouped.groupby('bin_no'):
        predictions[bin_no] = predict_next_fill(group)

    return predictions

def linear_regression_decision(df,threshold_multiplier=2):
    df['date'] = df['timestamp'].dt.date
    emptying_counts_per_day = df.groupby(['bin_no', 'date']).size().reset_index(name='emptying_count')

    bins_to_change = []
    for bin_no, group in emptying_counts_per_day.groupby('bin_no'):
        if len(group) <= 3:
            continue  # Skip bins with insufficient data

        mean_count = group['emptying_count'].mean()
        std_count = group['emptying_count'].std()

        # Check recent emptying counts (last 3 days) against threshold
        recent_counts = group.iloc[-3:]['emptying_count']
        change_needed = recent_counts.apply(lambda count: count > mean_count + threshold_multiplier * std_count).any()

        if change_needed:
            bins_to_change.append(bin_no)

    if bins_to_change:
        return f"Change needed for bins: {', '.join(bins_to_change)}"
    else:
        return "No change needed"


def plot_bin_data(df, output_dir='charts'):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if df.empty:
        print("No data to plot.")
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp', inplace=True)

    bins = df['bin_no'].unique()
    chart_urls = {}

    for bin_no in bins:
        plt.figure(figsize=(10, 5))
        bin_data = df[df['bin_no'] == bin_no]
        ax = bin_data.resample('D').count()['bin_no'].plot(kind='bar')
        plt.title(f'Fill Count for Bin {bin_no} Over the Last 15 Days')
        plt.xlabel('Date')
        plt.ylabel('Fill Count')
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Save plot to file
        file_path = os.path.join(output_dir, f'chart_{bin_no}.png')
        plt.savefig(file_path)
        plt.close()

        # Store URL to the chart
        chart_urls[bin_no] = f'/charts/chart_{bin_no}.png'

    # Save to JSON
    with open('chart_urls.json', 'w') as f:
        json.dump(chart_urls, f)
        print("img saved successfully")


def plot_and_decide_bin_changes(threshold=3):
    df = retrieve_bindata()

    if df.empty:
        print("No data to plot.")
        return

    print("Columns before processing:", df.columns)  # Debugging line
    if 'timestamp' not in df.columns:
        print("Error: 'timestamp' column is missing.")
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S')
    df.set_index('timestamp', inplace=True)

    bins = df['bin_no'].unique()
    decision = {}
    for bin_no in bins:
        plt.figure(figsize=(10, 5))
        bin_data = df[df['bin_no'] == bin_no]
        daily_counts = bin_data.resample('D').count()['bin_no']
        daily_counts.plot(kind='bar')
        plt.title(f'Fill Count for Bin {bin_no} Over the Last 15 Days')
        plt.xlabel('Date')
        plt.ylabel('Fill Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        # Decision making based on threshold
        average_fills = daily_counts.mean()
        if average_fills > threshold:
            print(
                f"Recommendation: Consider changing bin {bin_no}. Average daily fills ({average_fills:.2f}) exceed threshold ({threshold}).")
            decision[bin_no] = 'Change recommended'
        else:
            print(
                f"Bin {bin_no} is within acceptable fill limits (Average: {average_fills:.2f}, Threshold: {threshold}).")
            decision[bin_no] = 'No change needed'
    return decision


def analyze_and_plot_bins(df):
    """ Analyzes data for each bin, makes decisions, predicts using moving averages, and plots results. """
    results = {}
    for bin_no, group in df.groupby('bin_no'):
        print(f"Analyzing bin {bin_no}")
        prepared_data = prepare_data(group)
        forecast = moving_average_forecast(prepared_data, window_size=5)
        decision = linear_regression_decision(prepared_data)

        # Store results
        results[bin_no] = {
            'forecast_time': forecast,
            'decision': decision
        }

        # Plotting
        plt.figure(figsize=(10, 6))
        plt.plot(prepared_data['timestamp'], np.arange(len(prepared_data)), label='Fill Times')
        plt.title(f"Analysis for Bin {bin_no}")
        plt.xlabel('Time')
        plt.ylabel('Number of Fills')
        plt.legend()
        plt.grid(True)
        plt.show()

    return results
