"""
Schema Validator and Manager for Memory System.

Uses schema_metadata.json to validate and manage database schema.


"""

import sqlite3
import json
from pathlib import Path
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class SchemaValidator:
    """Validate and manage database schema using metadata."""

    def __init__(self, metadata_path: str = None):
        """
        Initialize schema validator.
        
        Args:
            metadata_path: Path to schema_metadata.json
        """
        if metadata_path is None:
            metadata_path = Path(__file__).parent / "schema_metadata.json"

        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)

        self.schema_version = self.metadata['schema_version']
        logger.info(f"Loaded schema metadata version {self.schema_version}")

    def validate_database(self, db_path: str) -> Dict[str, Any]:
        """
        Validate that database matches expected schema.
        
        Args:
            db_path: Path to SQLite database
            
        Returns:
            Validation result with status and details
        """
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        validation_result = {
            'valid': True,
            'schema_version': self.schema_version,
            'missing_tables': [],
            'missing_columns': {},
            'extra_columns': {},
            'type_mismatches': {}
        }

        # Check each table
        for table_name, table_spec in self.metadata['tables'].items():
            # Check if table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            )
            if not cursor.fetchone():
                validation_result['valid'] = False
                validation_result['missing_tables'].append(table_name)
                continue

            # Get actual columns
            cursor.execute(f"PRAGMA table_info({table_name})")
            actual_columns = {row['name']: row for row in cursor.fetchall()}

            # Check expected columns
            expected_columns = table_spec['columns']

            missing_cols = []
            for col_name, col_spec in expected_columns.items():
                if col_name not in actual_columns:
                    missing_cols.append(col_name)
                    validation_result['valid'] = False

            if missing_cols:
                validation_result['missing_columns'][table_name] = missing_cols

            # Check for extra columns (not in spec)
            extra_cols = [
                col for col in actual_columns if col not in expected_columns]
            if extra_cols:
                validation_result['extra_columns'][table_name] = extra_cols

        conn.close()

        return validation_result

    def get_column_definition(self, table_name: str, column_name: str) -> str:
        """
        Get SQL column definition from metadata.
        
        Args:
            table_name: Table name
            column_name: Column name
            
        Returns:
            SQL column definition string
        """
        col_spec = self.metadata['tables'][table_name]['columns'][column_name]

        definition = f"{column_name} {col_spec['type']}"

        if not col_spec.get('nullable', True):
            definition += " NOT NULL"

        if 'default' in col_spec:
            default = col_spec['default']
            if default == "CURRENT_TIMESTAMP":
                definition += f" DEFAULT {default}"
            elif isinstance(default, str):
                definition += f" DEFAULT '{default}'"
            else:
                definition += f" DEFAULT {default}"

        return definition

    def get_migration_sql(self, validation_result: Dict[str, Any]) -> List[str]:
        """
        Generate SQL migration statements to fix schema issues.
        
        Args:
            validation_result: Result from validate_database()
            
        Returns:
            List of SQL statements to run
        """
        sql_statements = []

        # Add missing columns
        for table_name, missing_cols in validation_result['missing_columns'].items():
            for col_name in missing_cols:
                col_def = self.get_column_definition(table_name, col_name)
                sql_statements.append(
                    f"ALTER TABLE {table_name} ADD COLUMN {col_def};"
                )

        return sql_statements

    def print_report(self, validation_result: Dict[str, Any]):
        """
        Print human-readable validation report.
        
        Args:
            validation_result: Result from validate_database()
        """
        print("\n" + "="*70)
        print("DATABASE SCHEMA VALIDATION REPORT")
        print("="*70)
        print(f"Schema Version: {validation_result['schema_version']}")
        print(
            f"Status: {'✅ VALID' if validation_result['valid'] else '❌ INVALID'}")
        print()

        if validation_result['missing_tables']:
            print("⚠️  Missing Tables:")
            for table in validation_result['missing_tables']:
                print(f"   - {table}")
            print()

        if validation_result['missing_columns']:
            print("⚠️  Missing Columns:")
            for table, columns in validation_result['missing_columns'].items():
                print(f"   {table}:")
                for col in columns:
                    print(f"      - {col}")
            print()

        if validation_result['extra_columns']:
            print("ℹ️  Extra Columns (not in schema):")
            for table, columns in validation_result['extra_columns'].items():
                print(f"   {table}: {', '.join(columns)}")
            print()

        if not validation_result['valid']:
            print("\n💡 To fix, run migration SQL:")
            migrations = self.get_migration_sql(validation_result)
            for sql in migrations:
                print(f"   {sql}")

        print("="*70 + "\n")


def validate_memory_database(db_path: str = "data/memory/incidents.db"):
    """
    Validate memory database schema.
    
    Args:
        db_path: Path to database file
    """
    validator = SchemaValidator()
    result = validator.validate_database(db_path)
    validator.print_report(result)

    return result


if __name__ == "__main__":
    # Run validation
    validate_memory_database()
