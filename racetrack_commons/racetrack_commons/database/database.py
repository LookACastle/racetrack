import os
from pathlib import Path
from typing import Dict


def populate_database_settings(base_dir: Path) -> Dict[str, Dict]:
    django_db_type: str = os.environ.get('DJANGO_DB_TYPE', 'sqlite')
    if django_db_type not in ['sqlite', 'postgres']:
        raise Exception("Error, unknown DJANGO_DB_TYPE: " + django_db_type)

    database_name = os.environ.get('POSTGRES_DB', '')
    if '{CLUSTER_NAME}' in database_name:  # evaluate templated database name
        cluster_hostname = os.environ.get('CLUSTER_FQDN')
        assert cluster_hostname, "CLUSTER_FQDN is not set"
        parts = cluster_hostname.split('.')
        if parts[0] == os.environ.get('RACETRACK_SUBDOMAIN', 'racetrack'):
            cluster_name = parts[1]
        else:
            cluster_name = parts[0]
        database_name = database_name.replace('{CLUSTER_NAME}', cluster_name)

    available_databases: Dict[str, Dict] = {
        'sqlite': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': base_dir / 'db.sqlite3',
        },
        'postgres': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': database_name,
            'USER': os.environ.get('POSTGRES_USER'),
            'PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
            'HOST': os.environ.get('POSTGRES_HOST'),
            'PORT': os.environ.get('POSTGRES_PORT'),
            'CONN_MAX_AGE': 60,
            'STATEMENT_TIMEOUT': 10,
            'OPTIONS': {
                'connect_timeout': 10,
            }
        }
    }

    return {
        'default': available_databases[django_db_type],
        django_db_type: available_databases[django_db_type],
    }
