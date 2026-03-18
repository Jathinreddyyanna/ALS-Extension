import type { Category } from './scan.types';

export interface DomainTrendPoint {
  date: string;
  riskScore: number;
}

export interface DomainTrend {
  current: number;
  previous: number;
  change: number;
  points: DomainTrendPoint[];
}

export interface CategoryCounts {
  [key: string]: number;
}

export interface DomainAggregate {
  categories: Category[];
  categoryCounts: CategoryCounts;
  riskScore: number;
  trustScore: number;
  reportCount: number;
}
