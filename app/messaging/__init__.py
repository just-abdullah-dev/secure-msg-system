# Initialize messaging package
from flask import Blueprint

bp = Blueprint('messaging', __name__)

from app.messaging import routes