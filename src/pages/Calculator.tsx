import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import DecoyCalculator from '@/components/Ghost/DecoyCalculator';

const Calculator = () => {
  const navigate = useNavigate();

  const handleExit = useCallback(() => {
    navigate(-1);
  }, [navigate]);

  return <DecoyCalculator onExit={handleExit} />;
};

export default Calculator;
