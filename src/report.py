from __future__ import annotations

from pathlib import Path  
import pandas as pd       
import matplotlib.pyplot as plt  


def ensure_dir(path: str | Path) -> Path:
    """
    Ensures that a directory exists.
    
    If the directory does not exist, it is created.
    
    Args:
        path (str | Path): The directory path to ensure exists
    
    Returns:
        Path: The Path object representing the directory
    """
    p = Path(path)  #Convert input to a Path object
    p.mkdir(parents=True, exist_ok=True)  #Create directory (including parents if needed), ignore if it already exists
    return p  #Return the Path object


def save_dataframe(df: pd.DataFrame, out_path: str | Path) -> None:
    """
    Saves a pandas DataFrame to a CSV file.
    
    Ensures that the output directory exists before saving.
    
    Args:
        df (pd.DataFrame): The DataFrame to save
        out_path (str | Path): The file path where the CSV will be saved
    """
    out_path = Path(out_path)  #Convert to Path object
    out_path.parent.mkdir(parents=True, exist_ok=True)  # nsure the parent directory exists
    df.to_csv(out_path, index=False)  #Save DataFrame to CSV without including row index




def plot_traffic_counts(counts_df: pd.DataFrame, out_path: str | Path) -> None:
    """
    Generates and saves a line chart of event counts over time.

    This function visualises how the number of events changes across time windows.

    Args:
        counts_df (pd.DataFrame): DataFrame containing:
            - 'window_start': time intervals
            - 'event_count': number of events per interval
        out_path (str | Path): File path where the plot image will be saved
    """
    
    #If the DataFrame is empty, there is nothing to plot
    if counts_df.empty:
        return

    out_path = Path(out_path)  #Convert output path to Path object
    out_path.parent.mkdir(parents=True, exist_ok=True) # Ensure output directory exists

    #Create a new figure for the plot
    plt.figure()

    #Plot event count over time
    plt.plot(counts_df["window_start"], counts_df["event_count"])

    # Label the axes
    plt.xlabel("Time window")
    plt.ylabel("Event count")

    #Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha="right")

    #Adjust layout to prevent label overlap
    plt.tight_layout()

    #Save the figure to the specified path
    plt.savefig(out_path)

    #Close the plot to free memory
    plt.close()