import { useEffect, useState } from 'react'
import { getAdminMe, getMe } from '../api/client'

export const useSession = () => {
  const [loading, setLoading] = useState(true)
  const [sessionRole, setSessionRole] = useState(null)
  const [sessionUser, setSessionUser] = useState(null)

  useEffect(() => {
    let active = true

    const loadSession = async () => {
      const [userResult, adminResult] = await Promise.allSettled([getMe(), getAdminMe()])
      if (!active) return

      const userSession = userResult.status === 'fulfilled' ? userResult.value : null
      const adminSession = adminResult.status === 'fulfilled' ? adminResult.value : null

      if (userSession?.login) {
        setSessionRole('user')
        setSessionUser(userSession)
        return
      }

      if (adminSession?.role === 'admin') {
        setSessionRole('admin')
        setSessionUser(adminSession)
        return
      }

      setSessionRole(null)
      setSessionUser(null)
    }

    loadSession().finally(() => {
      if (active) setLoading(false)
    })

    const handleExpiry = () => {
      if (!active) return
      setSessionRole(null)
      setSessionUser(null)
      setLoading(false)
    }

    window.addEventListener('auth:expired', handleExpiry)

    return () => {
      active = false
      window.removeEventListener('auth:expired', handleExpiry)
    }
  }, [])

  return {
    loading,
    sessionRole,
    sessionUser,
    isAuthenticated: sessionRole !== null,
    isAdmin: sessionRole === 'admin',
    isUser: sessionRole === 'user',
  }
}