import { createContext, useContext } from 'react'

export type NavigateOptions = {
  replace?: boolean
}

export type RouterContextValue = {
  pathname: string
  navigate: (to: string, options?: NavigateOptions) => void
}

export const RouterContext = createContext<RouterContextValue | null>(null)

function useRouter() {
  const value = useContext(RouterContext)
  if (!value) throw new Error('Router components must be rendered inside RouterProvider')
  return value
}

export function useLocation() {
  const { pathname } = useRouter()
  return { pathname }
}

export function useNavigate() {
  return useRouter().navigate
}
