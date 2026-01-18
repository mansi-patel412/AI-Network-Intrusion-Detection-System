import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
import joblib
import os

# Load dataset
df = pd.read_csv("packets.csv")

# Create label if not present
if "Label" not in df.columns:
    df["Label"] = [i % 2 for i in range(len(df))]

X = df.drop(columns=["Label"], errors="ignore")
y = df["Label"]

numeric_features = ["Length"]
categorical_features = ["Protocol"]

preprocess = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
        ("num", "passthrough", numeric_features),
    ]
)

model = Pipeline(
    steps=[
        ("preprocess", preprocess),
        ("classifier", RandomForestClassifier(n_estimators=100, random_state=42)),
    ]
)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/model.joblib")

print("\n✅ Model trained and saved to model/model.joblib")
