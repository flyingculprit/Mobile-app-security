import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.models import save_model
import joblib

# Load your dataset
data = pd.read_csv('features.csv')  # Assume you have a CSV with extracted features and labels

# Split into features and labels
X = data.drop('label', axis=1)
y = data['label']

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and fit the scaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Define the model
model = Sequential()
model.add(Dense(64, input_shape=(X_train_scaled.shape[1],), activation='relu'))
model.add(Dense(32, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

# Compile the model
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Check if the dataset size is sufficient for validation split
validation_split = 0.1
if len(X_train_scaled) > 10:
    model.fit(X_train_scaled, y_train, epochs=10, batch_size=32, validation_split=validation_split)
else:
    print("Dataset is too small for validation split. Training without validation split.")
    model.fit(X_train_scaled, y_train, epochs=10, batch_size=32)

# Save the model
model.save('models/security_detection_model.h5')

# Save the scaler
joblib.dump(scaler, 'models/scaler.pkl')