import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { EspaceMedecinPage } from './espace-medecin.page';

const routes: Routes = [
  {
    path: '',
    component: EspaceMedecinPage
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class EspaceMedecinPageRoutingModule {}
