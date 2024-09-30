const convertToMilliseconds = ({
  days = 0,
  hours = 0,
  minutes = 0,
  seconds = 0,
}: {
  days?: number;
  hours?: number;
  minutes?: number;
  seconds?: number;
}) => {
  const factors = [days, hours, minutes, seconds];
  const multipliers = [24, 60, 60, 1000];

  return factors.reduce(
    (acc, factor, idx) => (acc + factor) * multipliers[idx],
    0,
  );
};
export default convertToMilliseconds;
