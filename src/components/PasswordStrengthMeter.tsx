import { Check, Circle } from 'lucide-react';
import { evaluatePasswordStrength } from '../utils/authValidation';

interface PasswordStrengthMeterProps {
  password: string;
}

export function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
  const result = evaluatePasswordStrength(password);

  const barColor =
    result.score <= 1
      ? 'bg-red-600'
      : result.score === 2
        ? 'bg-amber-500'
        : result.score === 3
          ? 'bg-amber-500'
          : result.score === 4
            ? 'bg-blue-600'
            : 'bg-emerald-600';

  const rules = [
    { key: 'minLength', label: 'Mínimo de 8 caracteres', met: result.checks.minLength },
    { key: 'hasUppercase', label: 'Uma letra maiúscula (A-Z)', met: result.checks.hasUppercase },
    { key: 'hasLowercase', label: 'Uma letra minúscula (a-z)', met: result.checks.hasLowercase },
    { key: 'hasNumber', label: 'Um número (0-9)', met: result.checks.hasNumber },
    { key: 'hasSymbol', label: 'Um caractere especial (!@#$...)', met: result.checks.hasSymbol },
  ];

  return (
    <div className="mt-2.5 space-y-2.5" aria-live="polite">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-600 font-medium">Força da senha</span>
        <span
          className={`font-medium ${
            result.valid
              ? 'text-emerald-700'
              : result.score >= 3
                ? 'text-amber-700'
                : 'text-slate-600'
          }`}
        >
          {password ? result.label : 'Não preenchida'}
        </span>
      </div>

      <div className="grid grid-cols-5 gap-1.5" aria-hidden="true">
        {[1, 2, 3, 4, 5].map((step) => (
          <div
            key={step}
            className={`h-1.5 rounded-sm transition-colors duration-150 ${
              password && result.score >= step ? barColor : 'bg-slate-200'
            }`}
          />
        ))}
      </div>

      <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-3 gap-y-1 text-xs">
        {rules.map((rule) => (
          <li
            key={rule.key}
            className={`flex items-center gap-1.5 ${
              rule.met ? 'text-emerald-700 font-medium' : 'text-slate-500'
            }`}
          >
            {rule.met ? (
              <Check className="w-3.5 h-3.5 shrink-0 text-emerald-600" aria-hidden="true" />
            ) : (
              <Circle className="w-3 h-3 shrink-0 text-slate-300" aria-hidden="true" />
            )}
            <span>{rule.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
