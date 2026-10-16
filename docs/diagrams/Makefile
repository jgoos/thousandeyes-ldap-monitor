# LDAP Monitoring Diagrams Makefile
# Professional diagrams using AWS icons for semantic accuracy

.PHONY: all clean generate list help

# Default target - generate diagrams
all: generate

# Generate LDAP monitoring diagrams
generate:
	@echo "🚀 Generating LDAP monitoring diagrams..."
	@python3 -m venv venv --upgrade-deps || true
	@. venv/bin/activate && pip install -q -r requirements.txt
	@. venv/bin/activate && python3 ldap_monitoring.py

# List all generated files
list:
	@echo "📁 Generated LDAP monitoring diagrams:"
	@echo ""
	@if [ -d "output" ]; then \
		ls -la output/*.png 2>/dev/null | awk '{printf "• %s (%s KB)\n", $$9, int($$5/1024)}' || echo "   No diagrams found"; \
	else \
		echo "   No output directory found"; \
	fi

# Clean up all generated files and directories
clean:
	@echo "🧹 Cleaning up all generated files..."
	@rm -rf output/
	@rm -f *.png
	@echo "✅ All generated files removed"

# Clean up only the virtual environment
clean-venv:
	@echo "🧹 Cleaning up virtual environment..."
	@rm -rf venv/
	@echo "✅ Virtual environment removed"

# Full clean (files + venv)
clean-all: clean clean-venv
	@echo "✅ Complete cleanup finished"

# Show help
help:
	@echo "LDAP Monitoring Diagrams - Available Commands:"
	@echo ""
	@echo "  make all        - Generate LDAP monitoring diagrams"
	@echo "  make generate   - Generate LDAP monitoring diagrams"
	@echo "  make list       - List all generated diagram files"
	@echo "  make clean      - Remove all generated files and directories"
	@echo "  make clean-venv - Remove virtual environment only"
	@echo "  make clean-all  - Remove everything (files + venv)"
	@echo "  make help       - Show this help message"
	@echo ""
	@echo "Features:"
	@echo "  ✅ AWS icons chosen for semantic accuracy"
	@echo "  ✅ Generic LDAP monitoring setup"
	@echo "  ✅ Professional enterprise appearance"
	@echo "  ✅ Universal applicability to any LDAP environment"
	@echo "  ✅ One-command cleanup with 'make clean'"
	@echo ""
	@echo "Generated files:"
	@echo "  output/ldap_monitoring_architecture.png - Regional architecture"
	@echo "  output/ldap_monitoring_coverage.png     - Multi-layer validation"
	@echo "  output/validation_matrix.png            - Validation matrix"
	@echo "  output/monitoring_timeline.png          - Test sequence"
	@echo "  output/firewall_rules.png               - Firewall rules" 