from flask import Flask, request

app = Flask(__name__)

@app.route('/object/<path_param>')
def get_object(path_param):
    return {
        'path_param': path_param,
        'query_param': request.args.get('q', "'q' not set"),
        }

if __name__ == '__main__':
    app.run()
