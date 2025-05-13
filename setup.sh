#!/bin/bash

echo "🚀 Starting NayanTrix AI installation..."
for i in {1..3}; do
  curl -fsSL https://ollama.com/install.sh | sh && break
  echo "❌ Installation failed, retrying ($i/3)..."
  sleep 5
done

if ! command -v ollama &> /dev/null; then
  echo "❌ Critical: NayanTrix Ai installation failed!"
  exit 1
fi

echo "🔧 Starting NayanTrix service..."
sudo systemctl restart ollama
sleep 2

if ! systemctl is-active --quiet ollama; then
  echo "❌ NayanTrix Ai service failed to start!"
  exit 1
fi

echo "📦 Downloading AI model (NayanTrix Ai)..."
ollama pull gemma3:1b

echo "🐍 Installing Python dependencies..."
pip install -r requirements.txt

echo "✅ Setup complete! Start with: python app.py"
