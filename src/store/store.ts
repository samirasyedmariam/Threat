import { configureStore } from "@reduxjs/toolkit";
import { cveApi } from "./cveApi";

export const store = configureStore({
  reducer: {
    [cveApi.reducerPath]: cveApi.reducer,
  },
  middleware: (getDefault) => getDefault().concat(cveApi.middleware),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
