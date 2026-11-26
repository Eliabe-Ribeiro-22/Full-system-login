import { NextFunction, Request, Response } from 'express';
import { AccessTokenClaims, verifyAccessToken } from '../lib/authCrypto.ts';

export interface AuthenticatedRequest extends Request {
  auth?: AccessTokenClaims;
}

export function requireJwtAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Não autorizado: token JWT ausente.' });
  }

  const token = authHeader.slice('Bearer '.length).trim();
  if (!token) {
    return res.status(401).json({ error: 'Não autorizado: token JWT inválido.' });
  }

  try {
    const claims = verifyAccessToken(token);
    req.auth = claims;
    next();
  } catch {
    return res.status(401).json({ error: 'Sessão expirada ou token JWT inválido.' });
  }
}
