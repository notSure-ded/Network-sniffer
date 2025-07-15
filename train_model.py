import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Load the dataset
df = pd.read_csv("packet_dataset.csv")

# Encode the 'flags' column to numeric values
flags_encoder = LabelEncoder()
df["flags"] = flags_encoder.fit_transform(df["flags"])

# Encode the 'label' column ("normal", "suspicious") to numeric
label_encoder = LabelEncoder()
df["label"] = label_encoder.fit_transform(df["label"])

# Split features and label
X = df.drop("label", axis=1)
y = df["label"]

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the Random Forest classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate accuracy
accuracy = clf.score(X_test, y_test)
print(f"Model trained. Accuracy: {accuracy * 100:.2f}%")

# Save the model and encoders
joblib.dump(clf, "threat_model.pkl")
joblib.dump(flags_encoder, "flags_encoder.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")

print("Model and encoders saved.")
