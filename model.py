import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import preprocessor # Import the new module

def train_model_from_csv(filepath):
    """
    Loads data, uses a consistent preprocessor, and trains an Isolation Forest model.
    """
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        raise ValueError(f"Failed to read CSV file: {e}")

    # --- Preprocessing ---
    # We will use all columns for training except non-numeric ones that can't be encoded.
    # For this example, let's assume all object types are categories.
    
    df_features = df.copy()
    # A placeholder for a label if it exists, supervised models would use this.
    if 'Label' in df_features.columns:
        df_features = df_features.drop(columns=['Label'])

    # Create and save the preprocessor based on our training data
    proc, feature_names = preprocessor.create_and_save_preprocessor(df_features)
    
    # Transform the training data using the new preprocessor
    X_train_transformed = proc.transform(df_features)
    
    # --- Model Training ---
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    # Fit on the transformed data
    iso_forest.fit(X_train_transformed)
    
    print(f"Model trained on {len(feature_names)} features.")

    # Return the model and the names of the original columns it was trained on
    return iso_forest, df_features.columns.tolist()

