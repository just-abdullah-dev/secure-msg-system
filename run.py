from app import create_app

app = create_app()

# if __name__ == '__main__':
#     app.run(debug=True, ssl_context='adhoc')  # adhoc SSL for development

if __name__ == '__main__':
    app.run(debug=True, ssl_context=None)
