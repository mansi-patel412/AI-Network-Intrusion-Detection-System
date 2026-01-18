import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
import joblib
import os

def create_and_save_preprocessor(df, filename="model/preprocessor.joblib"):
    """
    Creates a preprocessing pipeline from the training data and saves it.
    This pipeline handles categorical features like IPs and Protocols.
    """
    # Identify categorical features to be encoded
    categorical_features = [col for col in df.columns if df[col].dtype == 'object']
    
    # All other columns will be passed through
    # We use OneHotEncoder which is great for non-ordinal data like IPs
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ],
        remainder='passthrough'  # Keep other columns (like 'len', 'port', etc.)
    )
    
    # Fit the preprocessor on the dataframe
    preprocessor.fit(df)
    
    # Save the fitted preprocessor
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    joblib.dump(preprocessor, filename)
    print(f"Preprocessor saved to {filename}")
    
    # Also return the feature names for clarity
    try:
        # Get feature names after one-hot encoding
        cat_feature_names = preprocessor.get_feature_names_out()
        all_feature_names = list(cat_feature_names)
    except Exception:
         # Fallback for older scikit-learn versions
        all_feature_names = categorical_features + [c for c in df.columns if c not in categorical_features]


    return preprocessor, all_feature_names

def load_preprocessor(filename="model/preprocessor.joblib"):
    """Loads the saved preprocessing pipeline."""
    return joblib.load(filename)
