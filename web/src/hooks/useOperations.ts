import { useQuery } from '@tanstack/react-query'
import { getAudits, getEvents, getExceptions, getFeedback, getPolicies, getReport, getUsers } from '../lib/api'

export const operationsKeys = {
  all: ['operations'] as const,
  audits: ['operations', 'audits'] as const,
  policies: ['operations', 'policies'] as const,
  users: ['operations', 'users'] as const,
  exceptions: ['operations', 'exceptions'] as const,
  feedback: ['operations', 'feedback'] as const,
  report: (days: number) => ['operations', 'report', days] as const,
  events: ['operations', 'events'] as const,
}

export function useAudits(enabled = true) {
  return useQuery({ queryKey: operationsKeys.audits, queryFn: () => getAudits(500), enabled })
}
export function usePolicies(enabled = true) {
  return useQuery({ queryKey: operationsKeys.policies, queryFn: getPolicies, enabled })
}
export function useUsers(enabled = true) {
  return useQuery({ queryKey: operationsKeys.users, queryFn: getUsers, enabled })
}
export function useExceptions(enabled = true) {
  return useQuery({ queryKey: operationsKeys.exceptions, queryFn: getExceptions, enabled })
}
export function useFeedback(enabled = true) {
  return useQuery({ queryKey: operationsKeys.feedback, queryFn: getFeedback, enabled })
}
export function useReport(days = 7, enabled = true) {
  return useQuery({ queryKey: operationsKeys.report(days), queryFn: () => getReport(days), enabled })
}
export function useEvents(enabled = true) {
  return useQuery({ queryKey: operationsKeys.events, queryFn: getEvents, enabled })
}
