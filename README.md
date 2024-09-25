<p align="center">
  <img alt="Phoenix", src="docs/img/phoenix-logo.png" width="30%" height="30%"></br>
</p>

# Prometheus-integrator

> Warning: This project is in active development, consider this before deploying it in a production environment.  All APIs, SDKs, and packages are subject to change.

## Documentation

The Prometheus-integrator is an integration backend between [prometheus](https://prometheus.io/) and the [Phoenix AMTD Operator](https://github.com/r6security/phoenix). To check what is an integration backend and how it is connected to other modules please consult with [the concepts page in phoenix operator](https://github.com/r6security/phoenix/blob/main/docs/CONCEPTS.md).

This integration is responsible to provide an entry point for Prometheus and to create Phoenix SecurityEvents. 

For more details about the Phoenix AMTD operator please visit its [repository](https://github.com/r6security/phoenix/).

## Caveats

* The project is in an early stage where the current focus is to be able to provide a proof-of-concept implementation that a wider range of potential users can try out. We are welcome all feedbacks and ideas as we continuously improve the project and introduc new features.

## Help

Phoenix development is coordinated in Discord, feel free to [join](https://discord.gg/zMt663CG).

## License

Copyright 2021-2024 by [R6 Security](https://www.r6security.com), Inc. Some rights reserved.

Server Side Public License - see [LICENSE](/LICENSE) for full text.