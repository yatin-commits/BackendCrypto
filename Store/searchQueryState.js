import { atom } from "recoil";

export const searchQueryState = atom({
  key: "searchQuery",
  default: "",
});

export const cryptoDataState = atom({
  key: "cryptoData",
  default: {},
});
