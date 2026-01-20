#!/bin/bash
# Quick test script for TfaBuster validation

echo "==================================================================="
echo "TfaBuster Quick Validation Script"
echo "==================================================================="

# Check if Flask server running
echo ""
echo "[1/3] Checking Flask server..."
if curl -s http://127.0.0.1:5555/health > /dev/null 2>&1; then
    echo "✓ Flask server is running"
else
    echo "✗ Flask server not running"
    echo "Start with: python tests/comprehensive_lab.py &"
    exit 1
fi

# Run automated test suite
echo ""
echo "[2/3] Running automated test suite..."
python tests/test_suite.py
TEST_RESULT=$?

# Run TfaBuster against one endpoint
echo ""
echo "[3/3] Running TfaBuster scan..."
python main.py \
    --target http://127.0.0.1:5555/api/verify-basic \
    --payload '{"otp":"0000"}' \
    | tail -20

echo ""
echo "==================================================================="
if [ $TEST_RESULT -eq 0 ]; then
    echo "✓ All tests PASSED"
    echo "Tool is ready for production use"
else
    echo "✗ Some tests FAILED"
    echo "Review test results above"
fi
echo "==================================================================="

exit $TEST_RESULT
