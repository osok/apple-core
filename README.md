# Apple-Core: Mach-O Analyzer

Apple-Core is a web-based tool for analyzing and modifying Mach-O binary files used by macOS and iOS applications.

## Features

- Upload and analyze Mach-O binary files
- View detailed header information
- Explore segment and section data
- Visualize memory layout
- Edit binary data with edit history tracking
- Supports 32-bit and 64-bit Mach-O formats
- Multi-architecture fat binaries

## Getting Started

### Prerequisites

- Python 3.8+
- pip package manager

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/apple-core.git
   cd apple-core
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

5. Run the application:
   ```
   flask run
   ```

6. Access the application at http://localhost:5000

## Usage

1. Upload a Mach-O binary file using the form on the homepage
2. Navigate through the analysis sections:
   - Overview: General file information
   - Headers: Mach-O header and load commands
   - Segments: Memory segments and their permissions
   - Sections: Code and data sections within segments
3. Use the hex editor to view and modify binary data
4. Track changes in the edit history

## Development

### Project Structure

```
apple-core/
├── app.py               # Entry point
├── config.py            # Configuration
├── requirements.txt     # Dependencies
├── static/              # Frontend assets
├── templates/           # HTML templates
└── core/                # Main package
    ├── __init__.py      # App factory
    ├── models/          # Database models
    ├── views/           # Flask routes
    ├── services/        # Business logic
    ├── forms/           # Form handling
    └── utils/           # Utilities
```

### Running Tests

Run tests with pytest:
```
pytest
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [macholib](https://github.com/ronaldoussoren/macholib) for Mach-O file parsing
- [LIEF](https://github.com/lief-project/LIEF) for binary format handling
- [Flask](https://flask.palletsprojects.com/) web framework 