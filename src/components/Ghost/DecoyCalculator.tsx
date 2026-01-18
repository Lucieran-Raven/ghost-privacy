import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';

interface DecoyCalculatorProps {
  onExit: () => void;
}

const DecoyCalculator = ({ onExit }: DecoyCalculatorProps) => {
  const [display, setDisplay] = useState('0');
  const [previousValue, setPreviousValue] = useState<number | null>(null);
  const [operation, setOperation] = useState<string | null>(null);
  const [waitingForOperand, setWaitingForOperand] = useState(false);

  // Secret exit: Type "73705" (GHOST upside down) then press =
  const [secretSequence, setSecretSequence] = useState('');

  const handleNumber = useCallback((num: string) => {
    setSecretSequence(prev => (prev + num).slice(-5));

    if (waitingForOperand) {
      setDisplay(num);
      setWaitingForOperand(false);
    } else {
      setDisplay(display === '0' ? num : display + num);
    }
  }, [display, waitingForOperand]);

  const handleOperation = useCallback((op: string) => {
    const inputValue = parseFloat(display);

    if (previousValue === null) {
      setPreviousValue(inputValue);
    } else if (operation) {
      const result = calculate(previousValue, inputValue, operation);
      setDisplay(String(result));
      setPreviousValue(result);
    }

    setWaitingForOperand(true);
    setOperation(op);
  }, [display, operation, previousValue]);

  const calculate = (a: number, b: number, op: string): number => {
    switch (op) {
      case '+': return a + b;
      case '-': return a - b;
      case '×': return a * b;
      case '÷': return b !== 0 ? a / b : 0;
      default: return b;
    }
  };

  const handleEquals = useCallback(() => {
    // Check for secret exit code
    if (secretSequence === '73705') {
      onExit();
      return;
    }

    if (operation && previousValue !== null) {
      const inputValue = parseFloat(display);
      const result = calculate(previousValue, inputValue, operation);
      setDisplay(String(result));
      setPreviousValue(null);
      setOperation(null);
      setWaitingForOperand(true);
    }
  }, [display, operation, previousValue, secretSequence, onExit]);

  const handleClear = useCallback(() => {
    setDisplay('0');
    setPreviousValue(null);
    setOperation(null);
    setWaitingForOperand(false);
    setSecretSequence('');
  }, []);

  const handleDecimal = useCallback(() => {
    if (!display.includes('.')) {
      setDisplay(display + '.');
    }
  }, [display]);

  const buttons = [
    ['C', '±', '%', '÷'],
    ['7', '8', '9', '×'],
    ['4', '5', '6', '-'],
    ['1', '2', '3', '+'],
    ['0', '.', '='],
  ];

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="fixed inset-0 bg-neutral-100 dark:bg-neutral-900 flex items-center justify-center z-[9999]"
    >
      <div className="w-full max-w-xs p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-xs uppercase tracking-[0.16em] text-neutral-500 dark:text-neutral-400">Calculator</div>
          <button
            type="button"
            onClick={onExit}
            className="text-xs uppercase tracking-[0.16em] text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
          >
            Exit
          </button>
        </div>

        {/* Display */}
        <div className="bg-neutral-200 dark:bg-neutral-800 rounded-xl p-4 mb-4">
          <div className="text-right text-4xl font-light text-neutral-900 dark:text-white truncate">
            {display}
          </div>
        </div>

        {/* Buttons */}
        <div className="grid grid-cols-4 gap-2">
          {buttons.map((row, rowIndex) => (
            row.map((btn, btnIndex) => {
              const isZero = btn === '0';
              const isOperator = ['÷', '×', '-', '+', '='].includes(btn);
              const isFunction = ['C', '±', '%'].includes(btn);

              return (
                <button
                  key={`${rowIndex}-${btnIndex}`}
                  onClick={() => {
                    if (btn === 'C') handleClear();
                    else if (btn === '=') handleEquals();
                    else if (btn === '.') handleDecimal();
                    else if (btn === '±') setDisplay(String(-parseFloat(display)));
                    else if (btn === '%') setDisplay(String(parseFloat(display) / 100));
                    else if (isOperator) handleOperation(btn);
                    else handleNumber(btn);
                  }}
                  className={`
                    ${isZero ? 'col-span-2' : ''}
                    ${isOperator ? 'bg-orange-500 hover:bg-orange-400 text-white' : ''}
                    ${isFunction ? 'bg-neutral-300 dark:bg-neutral-700 text-neutral-900 dark:text-white' : ''}
                    ${!isOperator && !isFunction ? 'bg-neutral-400 dark:bg-neutral-600 text-white' : ''}
                    rounded-full h-16 text-2xl font-medium
                    active:scale-95 transition-transform
                    flex items-center justify-center
                  `}
                >
                  {btn}
                </button>
              );
            })
          ))}
        </div>

        {/* Hidden hint - appears after 30 seconds */}
        <motion.p 
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.3 }}
          transition={{ delay: 30 }}
          className="text-center text-xs text-neutral-400 mt-8"
        >
          73705=
        </motion.p>
      </div>
    </motion.div>
  );
};

export default DecoyCalculator;
