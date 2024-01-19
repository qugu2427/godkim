package main

type SigningAlgorithm uint8

const (
	RSASHA1 SigningAlgorithm = iota
	RSASHA256
)

type Canonicalization uint8

const (
	Simple Canonicalization = iota
	Relaxed
)

type KeyType uint8

const (
	RSA KeyType = iota
)

type ServiceType uint8

const (
	All ServiceType = iota
	Email
)
