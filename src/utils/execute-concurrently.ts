export const awaitConcurrently = async (...tasks: Promise<any>[]) => {
  return await Promise.all(tasks);
};
