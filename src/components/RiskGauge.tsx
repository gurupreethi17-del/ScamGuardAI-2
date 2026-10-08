import React from 'react';
import { RiskLevel } from '../types/index.ts';

interface RiskGaugeProps {
  score: number; // 0 - 100
  level: RiskLevel;
  confidence: number;
  size?: 'sm' | 'md' | 'lg';
  showConfidence?: boolean;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  level,
  confidence,
  size = 'md',
  showConfidence = true,
}) => {
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  const getColorConfig = () => {
    switch (level) {
      case 'CRITICAL':
        return {
          textColor: 'text-rose-400',
          borderColor: 'border-rose-500/30',
          bgGradient: 'from-rose-500/20 to-rose-950/40',
          badgeBg: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
          strokeColor: '#f43f5e',
          accentColor: 'rose',
        };
      case 'HIGH':
        return {
          textColor: 'text-amber-400',
          borderColor: 'border-amber-500/30',
          bgGradient: 'from-amber-500/20 to-amber-950/40',
          badgeBg: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
          strokeColor: '#f59e0b',
          accentColor: 'amber',
        };
      case 'MEDIUM':
        return {
          textColor: 'text-yellow-400',
          borderColor: 'border-yellow-500/30',
          bgGradient: 'from-yellow-500/20 to-yellow-950/40',
          badgeBg: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30',
          strokeColor: '#eab308',
          accentColor: 'yellow',
        };
      case 'LOW':
      default:
        return {
          textColor: 'text-emerald-400',
          borderColor: 'border-emerald-500/30',
          bgGradient: 'from-emerald-500/20 to-emerald-950/40',
          badgeBg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
          strokeColor: '#10b981',
          accentColor: 'emerald',
        };
    }
  };

  const config = getColorConfig();

  // Circular gauge SVG metrics
  const radius = size === 'lg' ? 48 : size === 'md' ? 36 : 24;
  const strokeWidth = size === 'lg' ? 7 : size === 'md' ? 5 : 4;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;
  const svgSize = (radius + strokeWidth) * 2;

  return (
    <div className="flex items-center gap-4">
      {/* Circular Gauge */}
      <div className="relative flex items-center justify-center shrink-0">
        <svg
          width={svgSize}
          height={svgSize}
          className="transform -rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={svgSize / 2}
            cy={svgSize / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-slate-800"
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={svgSize / 2}
            cy={svgSize / 2}
            r={radius}
            stroke={config.strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span
            className={`font-mono font-bold tracking-tight tabular-nums ${
              size === 'lg' ? 'text-2xl' : size === 'md' ? 'text-lg' : 'text-sm'
            } ${config.textColor}`}
          >
            {normalizedScore}
          </span>
          {size !== 'sm' && (
            <span className="text-[10px] text-slate-500 font-mono -mt-1">/100</span>
          )}
        </div>
      </div>

      {/* Level and Confidence Metadata */}
      <div>
        <div className="flex items-center gap-2">
          <span className={`font-semibold tracking-wide ${config.textColor} ${size === 'lg' ? 'text-lg' : 'text-sm'}`}>
            {level} RISK
          </span>
          <span className="text-xs text-slate-500">·</span>
          <span className="text-xs text-slate-400 font-mono">
            {normalizedScore < 25
              ? 'No indicators · not verified safe'
              : normalizedScore < 50
              ? 'Some indicators'
              : normalizedScore < 75
              ? 'High risk'
              : 'Severe risk'}
          </span>
        </div>

        {showConfidence && (
          <div className="flex items-center gap-2 mt-1 text-xs text-slate-400 font-mono">
            <span>Confidence estimate: <span className="text-slate-200 tabular-nums">{confidence}%</span></span>
            <span>·</span>
            <span>Evidence-based</span>
          </div>
        )}
      </div>
    </div>
  );
};
