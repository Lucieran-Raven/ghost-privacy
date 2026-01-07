-- Create increment_rate_limit function if it doesn't exist
CREATE OR REPLACE FUNCTION public.increment_rate_limit(
  p_ip_hash text,
  p_action text,
  p_window_start timestamptz,
  p_max_count integer
) RETURNS boolean AS $$
DECLARE
  v_new_count integer;
BEGIN
  INSERT INTO public.rate_limits (ip_hash, action, window_start, count)
  VALUES (p_ip_hash, p_action, p_window_start, 1)
  ON CONFLICT (ip_hash, action, window_start)
  DO UPDATE SET count = public.rate_limits.count + 1
  RETURNING count INTO v_new_count;

  RETURN v_new_count <= p_max_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permissions
GRANT EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) TO service_role;
REVOKE EXECUTE ON FUNCTION public.increment_rate_limit(text, text, timestamptz, integer) FROM anon, authenticated;
