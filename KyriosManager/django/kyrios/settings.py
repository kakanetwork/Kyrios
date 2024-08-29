# ==================================================================================================================


from pathlib import Path
import os
from dotenv import load_dotenv


# ==================================================================================================================


""" CARREGA AS VARIAVÉIS GUARDADAS """

load_dotenv()


# ==================================================================================================================


""" VARIAVÉIS IMPORTANTES """

BASE_DIR = Path(__file__).resolve().parent.parent

PWA_SERVICE_WORKER_PATH = os.path.join(BASE_DIR,'templates','static', 'js', 'serviceworker.js')

LOGIN_URL = os.getenv('LOGIN_URL')

SECRET_KEY = os.getenv('SECRET_KEY')
 
DEBUG = True

RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')

# ==================================================================================================================


""" PRÁTICAS DE SEGURANÇA """

ALLOWED_HOSTS = ['analisador.cloud','www.analisador.cloud','127.0.0.1', '10.0.0.11']
CSRF_TRUSTED_ORIGINS = ['https://analisador.cloud', 'https://www.analisador.cloud', 'http://10.0.0.11']

#ALLOWED_HOSTS = ['analisador.cloud','www.analisador.cloud','127.0.0.1']
#CSRF_TRUSTED_ORIGINS = ['https://analisador.cloud', 'https://www.analisador.cloud']

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True


# ==================================================================================================================


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'pwa',
    'kyapp'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'kyrios.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.static',
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'kyrios.wsgi.application'


# ==================================================================================================================


DATABASES = {
     'default': {
         'ENGINE': 'django.db.backends.postgresql',
         'NAME': os.getenv('DB_NAME'),
         'USER': os.getenv('DB_USER'),
         'PASSWORD': os.getenv('DB_PASSWORD'),
         'HOST': 'localhost',
         'PORT': os.getenv('DB_PORT'),
     }
}

#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.sqlite3',
#        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'), # Você pode alterar o nome do arquivo de banco de dados se desejar
#    }
#}


# ==================================================================================================================


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# ==================================================================================================================


""" CONFIGURAÇÕES DE INTERNACIONALIZAÇÃO E LOCALIZAÇÃO """

LANGUAGE_CODE = 'pt-BR'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# ==================================================================================================================


""" CONFIGURAÇÕES DE ARQUIVOS ESTÁTICOS """

STATIC_URL = "/static/"
STATICFILES_DIRS = (os.path.join(BASE_DIR, 'templates/static'),)
STATIC_ROOT = os.path.join('static')


# ==================================================================================================================

""" CONFIGURAÇÕES PRINCIPAIS DO PWA """

PWA_APP_NAME = 'Kyrios'
PWA_APP_THEME_COLOR = '#ff0303'
PWA_APP_BACKGROUND_COLOR = '#000000'
PWA_APP_DISPLAY = 'standalone'
PWA_APP_ORIENTATION = 'portrait'
PWA_APP_ICONS = [
    {
        'src': '/static/img/icons/icon-192x192.png',
        'sizes': '192x192',
        'type': 'image/png',
    },
    {
        'src': '/static/img/icons/icon-512x512.png',
        'sizes': '512x512',
        'type': 'image/png',
    }
]

# ==================================================================================================================


""" CONFIGURAÇÕES SECUNDÁRIAS DO PWA """

DEBUG_PROPAGATE_EXCEPTIONS = True
COMPRESS_ENABLED = os.environ.get('COMPRESS_ENABLED', False)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': ('%(asctime)s [%(process)d] [%(levelname)s] ' +
                       'pathname=%(pathname)s lineno=%(lineno)s ' +
                       'funcname=%(funcName)s %(message)s'),
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        }
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        }
    },
    'loggers': {
        'testlogger': {
            'handlers': ['console'],
            'level': 'INFO',
        }
    }
}


# ==================================================================================================================
