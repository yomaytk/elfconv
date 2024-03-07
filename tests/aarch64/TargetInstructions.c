
long fcvtas_Xd_Dn(double val) {
  long res;
  asm("fcvtas %0, d0" : "=r"(res) : "w"(val) :);
  return res;
}

double frinta_Dd_Dn(double val) {
  double res;
  asm("frinta %d0, %d1" : "=w"(res) : "w"(val) :);
  return res;
}
