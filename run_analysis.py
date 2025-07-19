from app import app

if __name__ == '__main__':
    print("Starting Security Analysis Interface...")
    print("Access the analysis dashboard at: http://127.0.0.1:5000/analysis")
    app.run(debug=True, port=5000) 